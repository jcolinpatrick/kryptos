---
status: preregistered
locked_at: 2026-05-19
locked_by: Claude Opus 4.7 (1M context), at user direction "run H1"
contract: ../execution_contract.md
parent_hypothesis: results/final_report.md §5 H1
---

# E03 — H1 Pre-registration: Non-columnar middle-layer 3-stack sweep

## 1. Hypothesis (verbatim from final_report.md §5 H1)

> Multi-layer non-direct-positional, with a non-columnar middle layer.
> The TABP series tested only columnar middle layers exhaustively under
> outer transposition; non-columnar middle layers are the natural
> untested extension. Hard Blocker #3 explicitly names this as still
> partially explored.

## 2. Encryption / decryption models

Two distinct stack orders, each tested separately. Both are bounded
2-layer constructions with one substitution and one *non-columnar*
transposition.

**Model A (TABP shape, sub-after-trans on the encryption side):**
- Encryption: PT --[TRANS]--> intermediate --[SUB]--> CT
- Decryption: CT --[SUB^-1]--> intermediate --[TRANS^-1]--> PT
- The TABP series tested this with a columnar middle; H1 tests it
  with a non-columnar middle.

**Model B (sub-after-trans inverted — sub-then-trans on the encryption
side):**
- Encryption: PT --[SUB]--> intermediate --[TRANS]--> CT
- Decryption: CT --[TRANS^-1]--> intermediate --[SUB^-1]--> PT

Note: Model A and Model B are mathematically distinct because
transposition and (non-monoalphabetic) substitution do not commute.

## 3. Search universe (bounded; locked before run)

### Substitution layer (SUB)

- variant ∈ {Vigenere, Beaufort, Variant_Beaufort} — 3 cases
- alphabet ∈ {AZ, KA} — 2 cases
- keyword ∈ KEYWORD_POOL_K4 (locked below) — see size N_KEY
- period = len(keyword) (i.e. periodic with keyword as period)

KEYWORD_POOL_K4 (30 keywords; same pool as e02 plus 7 short K-section
neighbours):

```
KRYPTOS, PALIMPSEST, ABSCISSA,
BERLIN, CLOCK, BERLINCLOCK,
EAST, NORTHEAST, EASTNORTHEAST,
WORLD, WORLDCLOCK,
LANGLEY, WEBSTER, CARTER, HOWARDCARTER, TUTANKHAMUN,
LAYERTWO, INVISIBLE, IQLUSION, SHADOW, FORCES,
ATBASH, ALEXANDERPLATZ,
SCHEIDT, SANBORN,
MAGNETIC, EARTHSMAGNETIC,
LUCIDMEMORY, UNDERGRUUND, DESPARATLY
```

### Middle transposition layer (TRANS)

Non-columnar by construction:

- **Myszkowski**: same KEYWORD_POOL_K4 as the SUB layer; widths
  ∈ {5, 6, 7, 8, 9, 10, 11, 12, 13}.
  Cardinality: |KEYWORD_POOL_K4| × 9 = 270.
- **Rail-fence**: depths ∈ {2..15}. Cardinality: 14.
- **Route-spiral**: rectangle shapes ∈ {(w=7,h=14), (8,13), (9,11),
  (10,10), (11,9), (13,8), (14,7)} × directions ∈ {CW_from_NW,
  CW_from_NE, CCW_from_NW, CCW_from_NE}. Cardinality: 7 × 4 = 28.

Total middle-transposition configs: 270 + 14 + 28 = **312**.

### Total config count

For each model (A and B):
- N_configs = 3 × 2 × 30 × 312 = 56,160

For both models combined: **2 × 56,160 = 112,320 configs**.

### Universe hash

SHA-256 of a normalized, sorted JSON of:
- model_names = ["A_TRANS_then_SUB", "B_SUB_then_TRANS"]
- variants = ["vigenere", "beaufort", "var_beaufort"]
- alphabets = ["AZ", "KA"]
- keyword_pool = sorted(KEYWORD_POOL_K4)
- mysz_widths = [5,6,7,8,9,10,11,12,13]
- rail_depths = [2..15]
- spiral_shapes = sorted ((w,h,dir)) tuples
- total_configs = 112320

(Hash is computed and stored alongside the run output.)

## 4. Pre-registered thresholds (locked)

Three tiers; a candidate is escalated for verification at each tier.

### Tier 1 — exploratory storage threshold

- `crib_score >= 10` (NOISE_FLOOR per kernel constants).
- Action: write to `results/candidates.jsonl` for later inspection.

### Tier 2 — interesting (this is where the kernel's STORE label sits)

- `crib_score >= 10` AND **at least one** of:
  - `east_hits >= 8/13` (held in)
  - `bcl_hits >= 6/11` (held in)
- Action: log to `results/e03_h1_tier2.jsonl`.

### Tier 3 — pre-registered "promising" threshold (PASS)

A candidate passes the pre-registered H1 threshold iff **all** of:

1. `crib_score >= 18` (SIGNAL_THRESHOLD per kernel constants).
2. `holdout_EAST_hits >= 9/13` — i.e. when ONLY BCL is used as a
   target, the EAST crib positions independently come out correct
   in >= 9 of 13 places.
3. `holdout_BCL_hits >= 7/11` — symmetric.
4. Verification via `kryptos.kernel.scoring.aggregate.score_candidate`
   on the recovered plaintext: `bean_passed == True` AND
   `ngram_score / 97 >= -5.5`.

### Tier 4 — VERIFIED SOLVE (per execution_contract.md §3)

Requires full inverse-encryption byte-identity, English plaintext over
the non-crib positions, and red-team survival. **Tier 3 alone does NOT
constitute a solve** — it only authorizes Tier 4 verification.

## 5. Holdout protocol

For every candidate that hits Tier 2 or higher, we additionally:

- Withhold the EAST crib and read what the candidate predicts at
  positions 21–33; require >= 9/13 to clear Tier 3 condition 2.
- Withhold the BCL crib and read what the candidate predicts at
  positions 63–73; require >= 7/11 to clear Tier 3 condition 3.

Holdout is computed from the decrypted plaintext alone — no key tuning
on the withheld crib.

## 6. False-positive defenses (in addition to contract §5)

- Random expectation per crib position ≈ 1/26 → ≈ 4.3 hits / 112,320
  configs naively, but adjusted for the structured search this is
  meaningfully higher; the matched-null calibration is the right
  baseline, which is why Tier 3 mandates kernel-side
  `score_candidate` verification, not just naive crib counts.
- BERLINCLOCK as the SUB key on Variant Beaufort × KA produced the
  best partial holdout in e02 (4/11 BCL); confirm in this run whether
  that is structurally maintained, structurally elevated, or
  collapses under the addition of a middle transposition.
- Self-encrypting positions {32, 73}: any candidate that does not
  preserve these is automatically rejected.

## 7. Compute budget

- 112,320 configs at <= 0.5 ms each = ~ 56 s on a single core,
  ~ 2 s on the VM's 28 cores. No paid API calls.
- Budget: well under the $25 swing threshold that requires red-team
  review (`feedback_red_team_before_swings.md`). Zero token cost.

## 8. Stop conditions

- 0 candidates clear Tier 3 → clean null; report under
  `negative_results.md` and update `final_report.md` H1 disposition
  to "Tier 3 clean null, holdout verified, see e03 output".
- ≥ 1 candidate clears Tier 3 → halt enumeration; commission red-team
  review on the candidate (`feedback_red_team_before_swings.md`)
  before any Tier 4 advancement.

## 9. Reporting

- Append an E05 entry to `results/experiment_log.md`.
- Update `results/negative_results.md` with the clean-null tally if no
  Tier 3 pass.
- Update `results/final_report.md` §5 H1 with the post-run disposition.
- Surface counts and best-of-each-tier scores to the user at session
  end.

— locked —
