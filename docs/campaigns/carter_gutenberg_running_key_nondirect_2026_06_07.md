# Pre-registration — Carter-Gutenberg running-key inner under non-direct (post-transposition) alignment

**Date:** 2026-06-07
**Author:** autonomous `/goal` session (Claude Code)
**Alignment model:** `non_direct_alignment` (R1) — outer route reorders the carved
CT before the inner additive decrypt; cribs are scored in the PT frame after the
route is undone. `crib_alignment="post_transposition"`.
**Status at write time:** thresholds frozen BEFORE dispatch (results unseen).

This is the single next-best finite experiment named in
`results/final_k4_goal/FINAL_REPORT.md` §8: operationalize a declared, licensed
running-key corpus under a non-direct (post-transposition) alignment as ONE
bounded `HypothesisSpec` with a matched-family null and a hard kill criterion.

---

## 0. Why this is a NEW cell (not a re-run)

The 2026-06-05 closure (`docs/campaigns/non_direct_alignment_carter_tape_2026_06_05.md`,
commit `56d3392`) swept **Carter Vol.1** (`carter_vol1.txt`, the Carter & Mace
*The Tomb of Tut-ankh-Amen*, 287,417 offsets) × 52 routes × 3 variants × 2
alphabets = 89.7M configs → CLEAN_NULL. The 2026-05-28 C6 sweep
(`tools/workflows/k4_c6_tape_content/`) used 8 short K1/K2/K3-derived tapes.

This experiment uses a **different declared corpus** — `carter_gutenberg.txt`,
Project Gutenberg eBook #59783, *Tutankhamen and the Discovery of His Tomb*
(Carnarvon & Carter) — a DISTINCT public-domain text from Carter & Mace Vol.1.
Different tape content ⇒ different `universe_hash` ⇒ genuinely untested cell.
It is also the FIRST dispatch to score `post_transposition` Bean in the corrected
keystream frame (Task A fix, 2026-06-07): Bean is re-derived against the
route-undone PT-frame intermediate, not the carved CT.

## 1. Declared corpus (Task B)

| | |
|---|---|
| File | `reference/carter_gutenberg.txt` (present in repo) |
| Work | *Tutankhamen and the Discovery of His Tomb* (the Late Earl of Carnarvon & Mr. Howard Carter) |
| Source | **Project Gutenberg eBook #59783**, release 2019-01-28 (license embedded in-file) |
| License | **US public domain** — Project Gutenberg License text embedded in the file header |
| Provenance link to K4 | Howard Carter is the canonical Kryptos K3 source author (K3 PT paraphrases Carter's tomb-opening account). NOT leaked K4 plaintext. |
| Body extraction | text strictly between `*** START OF THE PROJECT GUTENBERG EBOOK ... ***` and `*** END ... ***`; uppercased; reduced to A-Z only (license boilerplate excluded from key material). |
| Body length | N = 101,923 A-Z letters; `body_sha256[:16] = 520192f7a0af0353` |

## 2. Preregistered HypothesisSpec (Task C)

- **outer layer (one explicit route):** `route_boustrophedon`, `width=14`,
  `vertical=False` (a single concrete serpentine; the cell is scoped to this route).
- **inner layer (one additive variant):** `key_tape`, `variant="vigenere"`,
  `alphabet="AZ"`, no nulls (running-key additive; the tape IS the keystream).
- **key material / window rules:** window = 97 contiguous body letters; direction
  = **forward**; stride = 1; offset o ∈ [0, N-97] ⇒ tape = body[o:o+97].
  Universe of offsets = **101,827**.
- **crib_alignment:** `post_transposition` (Task A: cribs anchored after route-undo;
  Bean re-derived in the route-undone PT frame).
- **scoring:** `composite` (kernel `score_candidate` + Bean re-derived in PT frame
  + per-char quadgram), with a **matched-family null** (§3).
- **expected_cardinality:** 1 route × 101,827 offsets × 1 variant × 1 alphabet
  = **101,827** configs.

## 3. Matched-family null + controls

- **Matched-family null:** identical structure (same route, variant, alphabet,
  window length, and **matched search depth** = all offsets) but with the corpus
  letters **shuffled** (Fisher-Yates on the body, fixed seeds), preserving unigram
  frequency while destroying word structure and any K4 relationship. M = 24 null
  trials. Report `null_beats_real = P(null_best_crib ≥ real_best_crib)` and the
  null best-crib distribution. (Matched depth defeats the order-statistic trap:
  max-of-101,827 real vs max-of-101,827 null per trial.)
- **Forced-crib control:** paste EASTNORTHEAST@21-33 + BERLINCLOCK@63-73 into an
  otherwise-random body, confirm crib_score=24 yet Bean FAIL and ngram below floor
  — demonstrating crib_score alone is not signal (AUDIT-3).

## 4. Hard kill criterion (frozen)

A candidate is **SIGNAL** iff ALL of:
1. `crib_score >= 18` (anchored, post-route-undo), AND
2. `bean_passed == True` (re-derived in the route-undone PT frame), AND
3. per-char quadgram `ngram_score >= -4.5` (English-body floor).

**Kill rule:** if NO config in the full 101,827-offset universe is SIGNAL, the
cell is declared `EXPERIMENT_COMPLETED_NULL`, scoped to the `universe_hash`.
A `crib_score >= 18` alone is NOT a solve and triggers
`results/final_k4_goal/verify_breakthrough.py` (full gate + controls), not a claim.

## 5. Scope of any negative

A null here closes ONLY:
`{carter_gutenberg body × boustrophedon(w=14, horizontal) × key_tape vigenere AZ ×
all forward window-97 offsets × post_transposition}`, identified by `universe_hash`.
It does NOT close: other routes, other variants/alphabets, reverse/other windows,
other corpora, or any direct-alignment model.

## 5a. Method addendum (discovered at run time, thresholds unchanged)

The DSL caps a single `ParamRange` at 10,000 values, so the full 101,827-offset
tape axis cannot be one `execute()` spec. Resolution (the validated pattern from
the 2026-06-05 89.7M-config Carter closure): the **full finite universe is scored
exactly** by a numpy crib prefilter, proven identical to the kernel
`score_candidate` crib on a random sample of offsets (integrity gate, must be 0
mismatches); the **high-crib survivors (+ all crib≥18) are kernel-verified by ONE
`execute()` dispatch** (`post_transposition`, Task A Bean frame + ngram). Because
SIGNAL requires crib≥18 and the prefilter covers every offset, the kill criterion
is evaluated over the entire universe. Thresholds in §4 are unchanged.

## 6. Replay

```
PYTHONPATH=src python3 -u scripts/campaigns/f_carter_gutenberg_running_key_nondirect_2026_06_07.py \
  --out results/final_k4_goal_next
```
Deterministic (no RNG except the fixed-seed null shuffles). Artifacts under
`results/final_k4_goal_next/`.
