# C1/C2 Downgrade Basis Note — 2026-04-08

**Purpose.** Companion to `docs/preregistered_thresholds_2026_04_08.md`.
Documents a post-execution policy correction that narrowed the corpus
allowlist without modifying the frozen pre-registration document or
weakening the downgrade conclusion. Written so that a future auditor
can reconstruct why the exhaustion certificate's downgrade of
running-key to bin B remains valid despite the allowlist change.

## Summary

- **Pre-registered downgrade criterion:** running-key downgrades to
  bin B iff C1 (Carter × columnar) AND C2 (Kahn × columnar) both
  complete with zero ESCALATED candidates
  (`docs/preregistered_thresholds_2026_04_08.md` §"DOWNGRADE criterion
  (for running-key as an open family)").
- **What actually happened on 2026-04-08:**
  1. 14:18 — `scripts/campaigns/f_final_checklist_c1_c2.py` runs
     both C1 and C2 as a single combined campaign. Result:
     zero Bean-passing orderings at widths {6,8,9} across all 3
     variants. Verdict EMPTY for both. Empirical basis was
     **running-key-source-independent within the analyzed cipher
     class** (see below).
  2. 14:23 — C6 runs separately, also EMPTY.
  3. Exhaustion certificate written
     (`docs/exhaustion_certificate_2026_04_08.md`) declaring
     running-key and non-columnar 3-layer both downgraded to bin B.
  4. ~15:30 — During a follow-up session, the allowlist entry for
     `kahn_codebreakers` was critiqued on principled grounds (see
     next section) and **revoked**.
- **This note** documents why the revocation does not retroactively
  invalidate the downgrade criterion, and what it does affect.

## Why `kahn_codebreakers` was revoked

The original `CREATOR_STATEMENT` license for Kahn was admitted because
Ed Scheidt publicly acknowledged reading *The Codebreakers* during
the K4 cipher design process. On reflection this conflated two
different uses of a text:

| Creator usage | Concerns | Justifies a running-key license? |
|---|---|---|
| Text was a **design reference** | How the cipher was built (mechanics) | **No** |
| Text was **embedded as key material** | What the cipher contains | Yes |

Scheidt's public record about Kahn is strictly the first kind. The
leap from "the consultant read this book" to "the key is inside this
book" is the exact guess-a-book pattern the admissibility framework
was built to reject.

A stronger operational test is the **derivation-pointer requirement**:
*could a solver, working only from Kryptos and its public record,
reasonably derive that this text is the running-key source?*

- **Carter Vol 1 passes.** K3's plaintext literally paraphrases
  Carter's tomb-opening passage, and Sanborn's AAA archive contains
  "Carter" correspondence. A solver discovers Carter by reading K3
  and following the reference.
- **Kahn fails.** Nothing in Kryptos itself points at Kahn. The only
  path from K4 to Kahn runs through Scheidt's extra-Kryptos reading
  list. A solver working from the puzzle alone cannot derive it.

The `CorpusJustification` docstring in
`src/kryptos/admissibility/corpus_policy.py` was updated in the same
commit to make this test explicit as policy, not just convention. See
`docs/admissibility_architecture.md` §"Revoked licenses" for the full
policy note.

## Why the downgrade remains valid

The downgrade of running-key to bin B rests on a
**running-key-source-independent Bean argument within the analyzed
cipher class**: columnar w6/8/9 × {Vig, Beau, VarBeau} on the carved
CT under direct positional crib mapping. Scope-corrected quote from
`docs/exhaustion_certificate_2026_04_08.md` §4 (updated 2026-04-09
under AUDIT-1 in `docs/methodological_audits.md`):

> **Within the analyzed cipher class — running-key + columnar w6/8/9
> × {Vigenère, Beaufort, Variant Beaufort}, applied to the carved
> 97-character CT under direct positional crib mapping — the full
> 242-inequality Bean constraint is violated by every (ordering,
> variant) pair.** No running-key source text can produce a solution
> *in that class*, regardless of length or content.

The Bean pre-filter eliminates all 403,920 orderings × 3 variants
before any running-key scan occurs. Carter, Kahn, and every
hypothetical allowlisted-or-not source all produce the same verdict
EMPTY because the running-key scan is never reached. Under the
corrected allowlist (Carter only), the same Bean pre-filter applies
and the same conclusion holds.

In other words: **the exhaustion certificate's downgrade rested on a
structural proof within a stated cipher class, not on a source-specific
empirical null**. Removing Kahn from the allowlist narrows the set of
admissible running-key hypotheses but does not change which of them can
satisfy the Bean constraint *in that class* — the answer remains zero.
The downgrade does **not** claim elimination of composed ciphers where
an outer layer precedes the columnar step; such compositions break the
direct positional crib mapping assumption and lie outside the analyzed
class.

## What the pre-reg document says vs. what we're doing

The pre-reg document is a **frozen commitment artifact**. From its
footer:

> *Committed 2026-04-08 before any compute. Changes to this document
> after any compute run invalidate the exhaustion certificate.*

We are **not modifying the pre-reg document.** This note is a
separate file that sits alongside it and documents the fact that the
downgrade condition the pre-reg specified ("C1 AND C2 both EMPTY")
was met as written, using the allowlist that was in effect at the
time of compute. The subsequent allowlist narrowing is a policy
correction for future work, not a retroactive modification of the
pre-reg.

Operationally:

- **Before 14:18 on 2026-04-08:** allowlist contained Carter + Kahn
  (+ K1/K2/K3 plaintexts). Pre-reg's "C1 AND C2 both EMPTY"
  condition applies to that 2-source basis.
- **14:18:** C1 + C2 both run, both EMPTY. The "C1 AND C2 both
  EMPTY" condition is satisfied as written.
- **After revocation (~15:30):** allowlist contains Carter only (+
  K1/K2/K3 + panel_ciphertext). Any future running-key campaign
  is restricted to this narrower set. The pre-reg's downgrade
  condition is already satisfied from the pre-revocation run.
- **Re-opening:** The `RE-OPENING criterion` in the pre-reg doc
  still applies. A new primary-source finding, a new detection
  apparatus, or a confirmed bug are the only valid re-opening
  triggers. The allowlist correction is not a re-opening — it does
  not add new admissible sources and does not change the empirical
  null.

## What future campaigns need to know

If you are starting a new running-key campaign after 2026-04-08:

1. **Check the current allowlist.** Only `carter_tomb_vol1`,
   `k1_plaintext`, `k2_plaintext`, `k3_plaintext`, and
   `panel_ciphertext` are currently admissible as running-key
   sources. Kahn is **not**.
2. **Check the exhaustion certificate.** Running-key + columnar
   w6/8/9 × {Vig, Beau, VarBeau} on the carved CT under direct
   positional crib mapping is already closed (running-key-source-
   independently, within that class) and requires a RE-OPENING
   criterion to touch again. See the pre-reg document for what
   counts. This does *not* close running-key composed with an
   outer layer that breaks the direct positional crib mapping.
3. **Check the session briefing.** The bin-C checklist renderer in
   `scripts/_infra/session_briefing.py` now reads result JSONs
   directly and will show C1/C2/C6/C7 as CLOSED if their artifacts
   are on disk. If it shows them as testable, an artifact path is
   missing and the briefing is stale — fix that first before
   launching any compute.
4. **Do not re-run** `f_final_checklist_c1_c2.py` without a new
   re-opening argument. The result is already committed.

## Timeline

- `2026-04-08T14:18:44` — `f_final_checklist_c1_c2.py` starts, runs
  10.3 seconds, writes `results/f_final_checklist_c1_c2.json`.
  Both C1 and C2 verdict EMPTY.
- `2026-04-08T14:23:10` — `f_final_checklist_c6.py` starts, runs
  43.4 seconds, writes `results/f_final_checklist_c6.json`.
  Verdict EMPTY.
- `2026-04-08T~14:30` — `docs/exhaustion_certificate_2026_04_08.md`
  written. Running-key and non-columnar 3-layer both downgraded to
  bin B.
- `2026-04-08T~15:30` — Follow-up session. C7 closure work
  (admissibility framework + corpus policy) committed as `6e6532d`.
- `2026-04-08T~16:30` — Allowlist review: `kahn_codebreakers`
  critiqued on derivation-pointer grounds and revoked. This note
  written.

## File references

- `docs/preregistered_thresholds_2026_04_08.md` (frozen, not
  modified)
- `docs/exhaustion_certificate_2026_04_08.md` (documents the
  empirical downgrade)
- `docs/admissibility_architecture.md` §"Revoked licenses" (policy
  reasoning)
- `src/kryptos/admissibility/corpus_policy.py` (allowlist + the
  retained revocation comment block above the position where Kahn
  used to live)
- `tests/test_admissibility.py::TestCorpusPolicy::test_kahn_is_not_allowlisted`
  (regression guard)
- `scripts/campaigns/f_final_checklist_c1_c2.py` (the canonical
  C1+C2 runner whose output the downgrade rests on)
- `results/f_final_checklist_c1_c2.json` (the canonical C1+C2
  result; verdict EMPTY for both)
