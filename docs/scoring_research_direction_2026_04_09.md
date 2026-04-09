# Scoring research direction — bin D1 reframed

**Date:** 2026-04-09
**Status:** Research memo. No compute commitment yet.
**Prerequisite:** Anyone building a non-quadgram K4 scorer should read this first.

---

## 1. Problem statement

On 2026-04-09 the red-team-disprover KILLED the proposal to build a
`search_fn` for the E-FRAC-54 joint two-sided detector
(`src/kryptos/detectors/efrac54_joint.py`). The structural argument was
that the joint detector is a *scoring function*, not a *search
algorithm*, and its scoring function (`_score_nats`, lines 142-168) is
**pure quadgram on both the PT side and the K_hat side**. The module's
own test suite already certifies that quadgram-only scoring cannot
distinguish real English from a Markov-3 adversarial surrogate at
n=97 (the "FM-1" result). Therefore no search over this scorer can
produce auditable signal, no matter how clever the search.

Full reasoning:
`/home/cpatrick/.claude/projects/-home-cpatrick-kryptos/memory/efrac54_search_fn_killed_2026_04_09.md`.

The verdict reclassified bin D1 from "engineering blocked on missing
search_fn" to "structurally blocked on a scorer that beats FM-1 at
n=97". This memo is the forward direction. It asks a concrete question:

> **What would a scorer have to do to beat FM-1 at n=97?**

If the answer is "nothing feasible", bin D1 is permanently closed and
the project's frontier is elsewhere. If the answer is "X, Y, or Z",
each becomes a testable sub-research-question with its own pre-flight
red-team.

---

## 2. Why quadgram fails — the information-theoretic argument

Quadgram scoring is a 3rd-order Markov model applied character-by-
character to a string. For a 97-character string:
- 94 4-grams are scored (positions 0..93)
- Each 4-gram produces a log-likelihood under an English 4-gram
  distribution
- The score per char is the mean over these 94 log-likelihoods

Information-theoretically, this is equivalent to asking:
**"What is the probability that this string was sampled from a
3rd-order Markov model trained on English?"**

A Markov-3 adversarial surrogate is, by construction, a string sampled
from that exact distribution. Its expected quadgram score is
indistinguishable from a real English string of the same length — the
expected log-likelihoods match, modulo finite-sample variance.

At n=97 the finite-sample variance of the mean log-likelihood is
roughly `sigma / sqrt(94)`, where sigma is the per-character
log-likelihood standard deviation in real English. Empirically this
gives a confidence interval wide enough that real English and Markov-3
adversarials overlap substantially. The detector's Gumbel calibration
absorbs the multiplicity budget but cannot create signal that the
scorer itself is blind to.

**Restating:** the quadgram scorer is to Markov-3 surrogates as a
frequency-analysis attack is to a one-time pad. The adversary has
perfectly matched the scorer's model, leaving no residual signal for
any search to exploit.

To beat FM-1 the new scorer must capture a property of English that
Markov-3 surrogates DO NOT preserve. That's the research question.

---

## 3. What do Markov-3 surrogates NOT preserve?

Let a "Markov-3 surrogate" be a string sampled character-by-character
from an English Markov-3 distribution (each character conditioned on
the previous 3 characters). The surrogate matches real English at the
4-gram frequency level by construction. What does it fail to match?

### 3.1 Long-range coherence

A Markov-3 chain has a context window of 3. Any property that requires
a context window longer than 3 is a potential discriminator. Concrete
examples:

- **Long-range topical consistency.** A paragraph about Berlin talks
  about Berlin at position 10 and at position 80. A Markov-3 surrogate
  has no notion of topic and will drift. Requires a topic model or a
  long-range LM.
- **Word-length distribution.** English words have a characteristic
  length distribution (Zipfian, mean ~4-5 characters). Markov-3
  surrogates preserve local digraph statistics but produce word-like
  chunks whose length distribution is narrower (short-biased) because
  they don't "know" to occasionally generate long compounds.
- **Syntactic consistency.** Real English sentences have grammatical
  structure (subject-verb agreement, parallelism). Markov-3 surrogates
  produce locally-plausible but globally-ungrammatical strings. A
  parser-based scorer could detect this.
- **Rare-word presence.** Real English contains rare words at a
  predictable rate (roughly one rare word per ~15 characters). Markov-3
  surrogates heavily over-sample common n-grams and under-sample rare
  words. A rare-word-density scorer could detect this.

### 3.2 Long-range structural patterns

- **Sentence boundaries.** English has a characteristic distribution
  of sentence lengths (mean ~15-20 words, with punctuation marking
  boundaries). Markov-3 surrogates have no notion of sentence and
  produce strings with anomalous punctuation or no sentence structure
  at all. NOTE: K4 is uppercase letters only, no punctuation, so this
  discriminator does not apply.
- **Paragraph structure.** Same issue — K4 is 97 chars, below the
  paragraph scale.

### 3.3 Higher-order n-gram statistics

- **5-gram, 6-gram, 7-gram scores.** These use context windows of
  4, 5, 6 respectively. A Markov-3 surrogate DOES preserve 4-gram
  statistics (trivially) but does NOT preserve 5-gram statistics
  (only up to the conditioning order). A 5-gram scorer should beat
  a Markov-3 surrogate in principle.

  **But**: at n=97, only 93 5-grams, 92 6-grams, 91 7-grams are
  present. With 26^5 ≈ 11.9M possible 5-grams, the counts are too
  sparse to reliably discriminate English from adversarial strings
  at this length. The test goes from signal-limited to variance-
  limited. This is why the E-FRAC-54 author chose quadgram in the
  first place.

### 3.4 Crib-boundary coherence (likely most promising)

This is the most promising discriminator because it is specific to
K4's crib structure and is NOT preserved by arbitrary Markov-3
sampling.

Setup: K4 has cribs at positions 21-33 (ENE) and 63-73 (BCL). These
24 positions are pinned in a real solution. The question is: does the
text immediately flanking the cribs (positions 16-20, 34-38, 58-62,
74-78) flow coherently into/out of the cribs?

Concrete example: a real solution that begins "...DESTINATION IS
EASTNORTHEAST..." has the character "ISEASTNORTHEAST" as a
5-character transition at position 19-23 that is highly probable under
any reasonable English LM. A Markov-3 surrogate applied to the cribs'
neighborhood produces transitions that look statistically normal LOCALLY
but do NOT preferentially form patterns like "IS", "TO", "THE",
"OF THE" immediately before "EASTNORTHEAST".

Formal definition: for each crib boundary position (four of them), define
a "junction score" as the log-likelihood of the 6-character window
spanning the boundary under an English 6-gram LM (or better, a neural
LM). Sum or average the four junction scores. Compare against shuffled
surrogates of the non-crib region.

This has two big advantages:
1. **It's orthogonal to quadgram.** A Markov-3 adversarial that matches
   real English on quadgram can still fail on junction coherence
   because the junctions are specific positions tied to the cribs.
2. **It uses the cribs as free signal.** The cribs are the highest-
   confidence information we have about K4. Scoring the text in their
   neighborhood exploits this.

### 3.5 Dictionary-word density

English text has roughly one dictionary word per ~5 characters. A
Markov-3 surrogate has approximately half that rate because Markov-3
transitions happily produce non-word sequences. Counting the number
of 4+ letter dictionary words in a candidate PT gives a discriminator.

The existing scoring pipeline has `word_scorer` infrastructure but
it is not wired into `score_candidate` by default (word_count is
None in the default breakdown). Wiring it in is cheap engineering.

This is NOT by itself enough to beat FM-1 because Markov-3 does
produce SOME words — just at roughly half the rate. The signal is
ratio-based and noisy at n=97. But it is ORTHOGONAL to quadgram
and can be combined with junction scoring.

---

## 4. Feasibility assessment at n=97

For each candidate scorer:

| Scorer | Beats FM-1? | Tractable? | Net |
|---|---|---|---|
| 5-gram / 6-gram / 7-gram | Yes in principle; variance-limited at n=97 | Yes (stdlib) | **Marginal** |
| Neural LM (GPT-2 small) | Yes; strongly | No (massive dependency, not stdlib) | Blocked by kernel policy |
| Word-boundary density | Partially | Yes (uses existing wordlists/english.txt) | **Good complement, not solo** |
| Junction coherence (crib-conditioned 6-gram) | Yes; orthogonal to quadgram | Yes (reuses quadgram infrastructure with a different indexing) | **Most promising** |
| Topic model | Yes | Expensive to train; gensim dependency | Not in scope |
| Parser-based | Yes | Requires a parser; not stdlib | Not in scope |
| Rare-word density | Partially | Yes | **Complement** |
| Syntactic n-gram (POS) | Yes | Requires POS tagger | Not in scope |

The three feasible directions under the kernel's stdlib-only policy:
1. **Junction coherence** (primary)
2. **Word-boundary density** (complement)
3. **5-gram extension** (marginal, variance-limited)

A composite scorer that combines (1) and (2) is more likely to beat
FM-1 than either alone. A 5-gram extension is worth trying as a
quick smoke test but should not be load-bearing.

---

## 5. Recommended experiment

**Experiment D1a: Junction coherence scorer**

Implementation:
1. Define a "junction" as a 6-character window centered on each crib
   boundary. Boundaries are at positions 20/21, 33/34, 62/63, 73/74.
   This gives 4 windows of 6 characters each = 24 characters total.
2. Score each junction window under the existing quadgram LM (as a
   sanity baseline) AND under a 6-gram LM (the real test).
3. Sum or average the 4 junction scores to get `L_junction`.
4. Calibrate `L_junction` on shuffled-CT surrogates the same way
   E-FRAC-54 calibrates `T`. Fit a Gumbel, derive a threshold.
5. Test against three plants:
   a. A REAL English plant (known solution mode)
   b. A Markov-3 surrogate plant (the FM-1 adversarial test)
   c. A randomly-shuffled non-crib plant (the noise floor)
6. **Verdict criterion**: L_junction beats FM-1 iff it distinguishes
   (a) from (b) with gap at least 3 beta under the Gumbel fit.

Expected compute: ~1-2 hours of engineering + 5-10 minutes of
calibration runtime at 10K surrogates per plant. No Opus budget
needed for the scorer itself; it's a single Python module. If the
verdict criterion passes, the search_fn build proposal can be
re-opened — the "change my mind" condition #2 from the KILL memo
is met.

If the verdict criterion fails: L_junction does NOT beat FM-1 at
n=97, and bin D1 remains closed. In that case, try combining with
word-boundary density (experiment D1b) before giving up.

**Experiment D1b: Composite junction + word-density scorer**

Same setup as D1a but the scoring function is a convex combination of
junction coherence and word-boundary density. The weighting hyper-
parameter is chosen to maximize the gap between real English and
Markov-3 on a held-out validation set BEFORE calibrating on K4. This
avoids peeking.

Expected compute: +1 hour engineering over D1a.

Neither experiment commits Opus budget. Both are pure engineering +
local VM compute.

---

## 6. What would move the verdict

From the red-team KILL memo, the three "change my mind" deliverables:
1. A recovery test from random sigma init (not round-trip, not planted).
2. A scorer upgrade beyond quadgram that provably beats FM-1 on the
   adversarial-blind test currently in the detector's test suite.
3. A proof that the gradient of T under single-letter sigma swaps
   exceeds the noise floor at n=97 for this cipher family.

This memo addresses (2). Experiments D1a and D1b are the concrete path
to moving the verdict on (2). If either experiment produces a scorer
that passes the FM-1 adversarial-blind test (with a pre-registered
threshold), the E-FRAC-54 search_fn proposal can be re-opened with a
new scoring function underneath it.

**Note on (1) and (3):** those are independent deliverables. A scorer
that beats FM-1 does not automatically give you a convergent hill-
climber; the gradient-floor argument must still be made. This memo
does not address them.

---

## 7. What this memo does NOT claim

1. It does NOT claim L_junction WILL beat FM-1. It claims L_junction
   is the most promising candidate under the stdlib policy and is
   worth the engineering investment.
2. It does NOT claim that beating FM-1 solves K4. A scorer that beats
   FM-1 still has to be paired with a tractable search and a
   cipher family that actually describes K4.
3. It does NOT replace the EFRAC-54 KILL. That verdict stands until a
   scorer passes the adversarial-blind test with a pre-registered
   threshold.
4. It does NOT recommend running any search on real K4. The first
   testable object is the scorer on planted/surrogate data, not K4
   itself.

---

## 8. Pre-flight for any implementation

Before any session commits to building experiment D1a or D1b:
1. Read `feedback_red_team_before_swings.md` (the gating rule)
2. Red-team the specific implementation choice (junction window size,
   n-gram order, combination function, calibration seed policy). This
   is NOT a trivial sanity check — the EFRAC-54 KILL showed that
   rhetorical claims of "escaping FM-1" do not survive contact with
   the actual scorer structure.
3. Pre-register the verdict criterion (3-beta gap or whatever the
   agreed number is) in a `docs/preregistered_*.md` file BEFORE any
   calibration run. Post-hoc threshold relaxation invalidates the
   result the same way it invalidates exhaustion certificates.
4. Use the same infrastructure discipline as E-FRAC-54: the search
   function / scoring function must be identical on planted data and
   on adversarial surrogates, and the `search_fn_hash` or equivalent
   must appear in the artifact.

---

## 9. Cross-references

- `memory/efrac54_search_fn_killed_2026_04_09.md` — the KILL memo
- `src/kryptos/detectors/efrac54_joint.py` — the detector being updated
- `docs/preregistered_thresholds_2026_04_08.md` — the threshold discipline template
- `feedback_red_team_before_swings.md` — the gating rule (session memory)
- `docs/exhaustion_certificate_2026_04_08.md` §11 — where bin D items
  are enumerated, including the "scorer research" direction this memo
  operationalizes.

---

*Memo by Claude Opus 4.6 during 2026-04-09 autonomous session.
No compute committed by this memo; it is a design document only.*
