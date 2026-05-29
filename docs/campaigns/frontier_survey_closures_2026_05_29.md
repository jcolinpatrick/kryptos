# Frontier survey closures — 2026-05-29 (session 2)

**Type:** analytical closures from an adversarial 5-lens frontier survey
(cipher / tape / stego / evidence / meta-statistical lenses + per-proposal
red-team + chancellor synthesis). No paid dispatch. Recorded per the
disproof-protocol; scope statements are explicit.

**Posture context.** A week of orthogonal Grade-A clean nulls (named-reorder
periodic inner, public-tape inner, C7 single-cut segmented tape) bottoming
uniformly at the noise floor with no rising near-miss density. The
meta-statistical lens put the posterior that an *untested analytical cell*
contains the K4 solve at **~1–3%**. These two closures remove the strongest
remaining *tempting* analytical carve-outs so they are not re-proposed.

---

## CLOSURE 1 — KILL: two superimposed additive keys, NO transposition

**Move (proposed, cipher lens):** apply `K_eff[i] = (K1[i mod p1] + K2[i mod p2])
mod 26` as a single additive keystream to the canonical 97-char CT under direct
positional crib mapping (NO interposed transposition), coprime `2 ≤ p1 < p2 ≤ 13`,
all 3 additive variants, both alphabets; solve the 24 crib equations as an exact
CSP over Z26 and score the forced non-crib plaintext.

**Verdict: KILLED — subsumed by E-FRAC-35.** Verified by enumeration (red-team)
and independently re-derived. The two desirable properties are **provably
disjoint**:

1. A sum of two periodic keys is itself a single periodic key of period
   `L = lcm(p1, p2)`.
2. The only coprime pairs for which *all 73 non-crib positions are FORCED* by
   the cribs are `(2,3), (2,5), (3,4), (3,5)` → `L ∈ {6, 10, 12, 15} ≤ 26`, all
   inside the certified "all periodic substitution periods 1–26 eliminated on the
   raw 97-char carved text" closure (E-FRAC-35, full 242-inequality Bean set).
3. Every coprime pair with `L > 26` (the proposal's claimed escape from
   E-FRAC-35) leaves ALL 73 non-crib positions FREE — the high-period
   underdetermined regime that produces only false positives (Bean references
   only the 24 crib positions, so it cannot discriminate the free DOF).

So "the non-crib plaintext is forced (scorable)" and "the effective period
escapes E-FRAC-35" never hold simultaneously. Negligible prior; do not run.

**Scope:** direct_ct_pt alignment, additive (Vig/Beaufort/VarBeaufort) double-key
overlay with NO transposition. (E-FRAC-52 already covers the WITH-columnar-layer
`K_eff[j] = K1[j%p1] + K2[inv(j)%p2]` form; this closes the identity-transposition
case that E-FRAC-52 reached only by analytical extension.)

---

## CLOSURE 2 — DEPRIORITIZE (record by decomposition proof): C8 two-independent public-tape segments

**Move (proposed, tape lens):** keystream = cut-concatenation of TWO DISTINCT
public tapes `K[i]=T_A[i]` for `i<C`, `K[i]=T_B[i-C]` for `i≥C`; `T_A ≠ T_B` from
the 16-tape public corpus; single cut `C ∈ {34..62}` (inter-crib gap, voids Bean
`k[27]=k[65]`); 3 variants. 240 tape-pairs × 29 cuts × 3 = 20,880 configs,
Category-B.

**Verdict: DEPRIORITIZE — eliminable by decomposition proof, prior ~1e-5.** The
only new DOF over the already-CLEAN_NULL C7 single-cut run
(`c7_segmented_public_tape_2026_05_29.md`) is a SECOND independent draw from the
identical 16-tape corpus, whose members were already individually shown to carry
no English advantage over random tapes under the same anchored pipeline and
matched null (C6 public tape-content; 52-route public inner mean-eq p=0.897; C7
single-cut max_crib 5/24, `null_beats_real=True`, mean-eq p=0.183). With a
disjoint-segment cut the per-crib-group score is additively capped (each crib
group sees exactly one segment), pinning max crib near 5/24 — far below signal —
with n-gram below the −4.5/char floor. Two no-signal draws cannot compose into
inter-crib English; the matched null absorbs the second-tape freedom
symmetrically. **Not in `exhaustion_log.json`** (un-run); recorded here as a
proof-backed deprioritization, NOT a hash-locked exhaustive negative. Run only if
some upstream result escalates it.

**Scope:** direct_ct_pt, two distinct PUBLIC tapes, single cut in {34..62}. NOT
closed: non-public tapes, crib-forced segment keys, cuts outside the gap,
two-segment masks under non-direct alignment.

---

## Instrument repair (same session)

The GAP-09 T2 closure null (`gap09_colocation.gap09_t2_colocation_p`, uniform
hypergeometric) was found **misspecified for structured (periodic) masks against
structured (periodic) observables** — reproduced firing `p=6.66e-08` (below the
1e-6 gate) on a period-14 mask vs period-14 line-breaks with ZERO stego content.
Fixed with a periodicity-matched null (`gap09_t2_colocation_p_matched` +
`periodic_rule_masks`); same confound → `p=0.13`. See
`docs/REAL_K4_GAP09_ACQUISITION_SPEC_2026_05_29.md` §2 caveat and
`tests/test_gap09_colocation.py` (12 green). Any future O1 closure on a periodic
mask MUST use the matched null.

---

**Bottom line:** bounded analytical sweeping is no longer rational (posterior
~1–3%). Real P(solve) lives behind GAP-09 physical evidence acquisition (a
flat/frontal orthographic K4 panel photo for carved line-breaks), now gated
behind the repaired matched null. K4 NOT solved.
