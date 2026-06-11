# Pre-registration: cryptonym-crib keystream back-derivation screen (2026-06-11)

**Run:** `results/cryptonym_crib_screen_2026_06_11/`
**Provenance (admission rules 1-2):** IMG_1571 (primary-verified 2026-06-11,
this session): Sanborn's hand lists the cryptonym formation rule ("2 letters
determine general category or place, followed by letters that form a word
with the first two") and three specific tokens: **KUBARK** (= CIA),
**FLUTTER** (= polygraph), **OVERLORD** (underlined). Mechanism mapping:
hypothesized plaintext crib at a declared position under direct positional
alignment; each (CT, PT) pair back-derives one keystream letter per
convention. A keyword-periodic cipher with key phase 0 would expose its
leading key letters directly; a word-like derived fragment is the
detectable side-effect (rule 7).

**Alignment model:** `fixed_len_97` / direct positional (H1). Results are
H1-conditional. Free-alignment and Quagmire-tableau extensions are named
follow-ups, not part of this screen.

**Prior art (checked):** `e_digraph_running_key_01` tested digraphs only in
the running-key-source role (v2/v3 archived, C7-rejected);
`digraph_anchored_search` / `digraph_constrained_sa` are NOISE verdicts
built on the RETIRED 24-null-mask model — contaminated, non-binding.
KUBARK/FLUTTER/OVERLORD are not in the thematic keyword list (untested as
cribs in the live frame).

## Frozen universe (Tier 1, primary — page-attested tokens only)

- Cribs: KUBARK (6), FLUTTER (7), OVERLORD (8).
- Positions: every start in the pre-ENE region with full containment,
  p in 0..(21-L) (Colin's "likely beginning"; the region carries no crib
  today). 16+15+14 = 45 placements.
- Conventions: K = CT-PT (vigenere), CT+PT (beaufort), PT-CT
  (variant_beaufort), each over AZ(A=0) and KA index tables = 6 cells.
- Total fragments: 45 x 6 = 270 tests (declared multiplicity).

**Tier 2 (exploratory, declared, NOT run in this screen):** broader public
CIA cryptonym lists; other gap regions (34-62, 74-96); nonzero key phases;
Quagmire III tableau conventions.

## Statistics and decision rules (FROZEN)

- Per fragment: (a) exact dictionary membership (wordlists/english.txt);
  (b) prefix-of-dictionary-word; (c) per-char quadgram score.
- Null: derived fragments under a uniform random crib are uniform random
  L-grams (PT uniform implies K uniform for fixed CT, all three variants);
  null rates estimated by 200,000 random L-grams per length against the
  same dictionary (seed 20260611).
- Primary test: observed count of exact-word fragments across the 270
  cells vs Binomial(270, p_null_L) expectation (lengths pooled by
  expectation); secondary: prefix counts, max quadgram vs null max.
- **Candidate rule:** any exact-word fragment -> investigate-first (it is
  a keyword CANDIDATE, not a finding): decrypt the full CT under the
  implied keyword/convention and kernel-score (anchored, disclosed cribs)
  before any claim. Word-like fragments are EXPECTED at the null rate;
  only an excess or a fragment that survives full-decrypt scoring matters.
- **Kill rule:** counts within null expectation and no fragment surviving
  full-decrypt scoring -> screen closes MEASURED_NULL; the cryptonym-crib
  idea then needs the Tier-2/engineering extensions to proceed, not
  re-runs of this universe.
- Known-answer gate (inline, fail-closed): the same derivation code must
  reproduce the kernel's disclosed-crib keystream constants at ENE/BC for
  all three variants (AZ) before any Tier-1 fragment is computed.

## Tier 2a — Quagmire III extension (frozen 2026-06-11 BEFORE run)

- Same cribs and placements as Tier 1 (3 page-attested tokens, 45 pre-ENE
  placements). New axis: QIII tableau conventions (the K1/K2 family).
- Tableau keyword (pt = ct alphabet keyword, QIII): {KRYPTOS, PALIMPSEST,
  ABSCISSA, LATITUDE, MAGNETIC, COMPASS} — KRYPTOS is the sculpture's own
  K1/K2 convention (strongest prior); the other five are the precedented
  set from the route x QIII campaign. Indicator: {K, A, R} (K1/K2 actual
  is K). 45 x 6 x 3 = 810 fragments (declared multiplicity).
- Derivation through the KERNEL: shift = quagmire_recover_key(ct, pt,
  kw, kw, indicator); key letter = ct_alpha[(shift + ct_idx[indicator]) %
  26]. Known-answer gate (fail-closed): exhaustive single-char inversion
  self-test over all 26 pt x 26 key letters per convention cell must
  recover the key letter exactly; kernel QIII correctness itself is
  anchored by the standing K1/K2 regression tests.
- Statistics, null (uniform L-gram; the pt-to-keyletter map is a bijection
  for fixed ct, so uniform crib gives uniform fragment), and decision
  rules identical to Tier 1. Expected exact-word fragments ~0.09 under
  the null. Phase-0 simplification still applies (contiguous fragment);
  nonzero phases remain open.
