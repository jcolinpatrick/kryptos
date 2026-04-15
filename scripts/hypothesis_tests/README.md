# Hypothesis-test harnesses

Deterministic finite harnesses for cipher-family hypotheses that would
otherwise be tested via timeout-prone agent-worker paths. Each harness in
this directory is a **standalone reproducible campaign**: it constructs a
finite universe, runs kernel-verified checks, checkpoints progress, and
returns an explicit epistemic outcome.

## Available harnesses

### `h_624_73_nullmask_harness.py`

The 73-real / 24-null / Bean-admissibility family. Tests the hypothesis
that 73 of the 97 characters in K4 CT are "real" ciphertext and 24 are
"nulls" deleted under some positional mask, with the real ciphertext
decrypted by an additive cipher (Vigenere / Beaufort / Variant Beaufort)
using a periodic keyword keystream.

Supports modes:

- `inventory` -- print and write the candidate universe, no evaluation
- `smoke` -- tiny bounded run (small mask + key limits)
- `full` -- full structured enumeration up to `--max-configs`

Built-in parallelism via `multiprocessing.Pool` with a per-worker ngram
scorer initializer. Default worker count is `max(1, cpu_count() - 2)`.

#### How the controller should interpret this harness's output

| Outcome                  | Meaning                                                                                      |
|--------------------------|----------------------------------------------------------------------------------------------|
| `ELIMINATED`             | Full finite coverage completed, zero survivors >= STORE. **Conditional** on stated assumption bundle. NOT a global K4 elimination. |
| `INCONCLUSIVE_BUDGET`    | Budget or time limit hit before full coverage. Partial data; do NOT treat as elimination.   |
| `INCONCLUSIVE_TOOLING`   | Required tooling (e.g. quadgram scorer) unavailable. No epistemic conclusion.               |
| `CANDIDATE_SIGNAL`       | At least one survivor at or above `SIGNAL_THRESHOLD`. **Not** a solution claim. Route through normal Day 5/6 alert + stat-audit + provenance gates before any promotion. |
| `ERROR`                  | Unhandled failure; see `notes` in output JSON.                                              |

#### Rules for controller integration

1. **Timeout is not elimination.** If a run is killed at 30m, the outcome
   must be `INCONCLUSIVE_BUDGET`, never `ELIMINATED`.
2. **Partial coverage is not elimination.** Coverage fraction < 1.0 means
   residual space is untested. Report as inconclusive.
3. **Full finite coverage with zero survivors is a CONDITIONAL elimination**
   within the stated `assumptions` bundle only. It does not falsify any
   mask or key family outside the enumerated set.
4. **Candidate signals still go through Day 5/6 gates.** A result from
   this harness does not bypass stat-audit, ngram floor, provenance gates,
   or the BREAKTHROUGH-fabrication defenses. The harness outputs
   kernel-verified `crib_score` and `bean_passed`; downstream gates do
   the rest.
5. **Nothing here writes to authoritative elimination logs.** The harness
   does not touch `exhaustion_log.json`, `docs/elimination_tiers.md`, or
   the kryptosbot ledger. Promoting an outcome is a separate, deliberate
   step performed only after human review.

#### Reproducing a run

Every output JSON and markdown report embeds an exact reproduction command.
Assumptions bundle + universe hash are pinned into the checkpoint; resume
refuses to continue across bundle or universe changes unless `--force` is
passed (and the override is recorded in the output `notes`).

#### Known limitations

- Mask universe is the **structured** union of head/tail blocks, periodic
  steps, residue classes, width-derived rows and columns. It is NOT a full
  C(73, 24) ~ 1.9e17 enumeration (physically infeasible). Random sampled
  masks are available behind a flag and explicitly labelled non-exhaustive.
- Key universe is the thematic wordlist (~400 words) with optional english
  short-word breadth (capped). Random or programmatic key generators are
  not in scope for this harness.
- Bean admissibility is fully applicable only for **crib-preserving** masks
  (the primary family). Non-crib-preserving masks are labelled
  `assumption_violated` and contribute zero to the scoring pool.
- A null hypothesis in which the 24 "nulls" obey a *content-level* rule
  (specific letters in the null palette) rather than a *positional* rule
  is NOT tested here. That belongs to a separate stego-layer harness.

#### Typical command lines

```bash
# Inventory only — no evaluation, cheap:
PYTHONPATH=src python3 scripts/hypothesis_tests/h_624_73_nullmask_harness.py --mode inventory

# Smoke run:
PYTHONPATH=src python3 scripts/hypothesis_tests/h_624_73_nullmask_harness.py --mode smoke --workers 4

# Full structured coverage with thematic keywords, parallelized:
PYTHONPATH=src python3 scripts/hypothesis_tests/h_624_73_nullmask_harness.py --mode full --workers 24

# Full + english-short breadth (slower):
PYTHONPATH=src python3 scripts/hypothesis_tests/h_624_73_nullmask_harness.py --mode full --workers 24 --include-english-keys --limit-keys 2000

# Resume an interrupted run (same assumptions + universe required):
PYTHONPATH=src python3 scripts/hypothesis_tests/h_624_73_nullmask_harness.py --mode full --workers 24 --resume
```
