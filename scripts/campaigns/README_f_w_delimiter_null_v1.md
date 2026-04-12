# f_w_delimiter_null_v1 — W-delimiter null elimination

Publication-grade distributional null test for the hypothesis that the
letter W in Kryptos K4 ciphertext acts as a delimiter (or null),
segmenting K4 into 6 runs at positions {20, 36, 48, 58, 74}.

## What this tests

Under the W-delimiter assumption, two of the 6 segments contain free-fill
slots adjacent to the known cribs:

| Slot | Positions | Len | CT | Role |
|---|---|---|---|---|
| A | 34-35 | 2 | OT | follows EASTNORTHEAST, precedes W delimiter |
| B | 59-62 | 4 | INFB | follows W delimiter, precedes BERLINCLOCK |

For every (slot A, slot B) fill in a set of populations, compute the
augmented keystream over the 30-position crib set under three additive
cipher variants (Vigenere, Beaufort, Variant Beaufort) and score it on
seven independent feature channels:

1. `new_zero_count` — new self-encrypting positions added (cheap, capped)
2. `new_equality_with_27_or_65` — how many new positions share the canonical Bean equality key value
3. `common_bigram_count` — English bigrams in the augmented keystream string
4. `common_trigram_count` — English trigrams
5. `contains_known_keyword` — substring match for KRYPTOS / PALIMPSEST / ABSCISSA / BERLIN / CLOCK / SANBORN
6. `semantic_coherence_score` — rule-based A+B grammatical coherence
7. `fill_complexity` — description-length penalty from English frequency proxy

Per-channel contributions are **capped** so no single channel can drive
the composite by itself.

## The four populations

| Population | Size | Rule |
|---|---|---|
| random | N (default 50k) | uniform A-Z x A-Z, seed-deterministic |
| dictionary | N (default 100k) | ASCII 2-letter x 4-letter English words |
| grammatical | 23 x 45 = 1035 | rule-based POS-curated (prep/pronoun/copula x spatial/temporal/structural/verbal) |
| curated | 4 x 6 = 24 | strictest: slot A in {TO,AT,IS,BY}, slot B in {NEAR,ATOP,UPON,INTO,PAST,FROM} |

## Verdict types

- **STRONG_ELIMINATION** — no candidate clears the multi-channel joint-tail criterion; top composite scores are explainable by combinatorics.
- **NARROW_RESIDUAL** — some specific candidate(s) clear joint-tail but not the curated+multiplicity bar. Requires follow-up, not a claim.
- **UNEXPECTED_HIT** — one or more candidates clear joint-tail AND multiplicity-aware curated bar. Candidate for replication, still not a claim.

## Joint-tail criterion

A candidate is joint-tail only if it is in the top 1% of the **grammatical**
population on at least 2 independent feature channels. Single-channel tails
are explicitly rejected.

## Scope limits (unavoidable)

- Only slots A and B are testable under current cribs
- Segments 0, 2, 3, 5 are NOT covered
- Only additive cipher variants are tested
- Direct positional alignment CT[i] -> PT[i] is assumed
- The W-delimiter hypothesis itself is a working assumption, not proven

## Usage

```bash
# Default run (all variants, all populations, 50k random + 100k dictionary)
PYTHONPATH=src python3 -u scripts/campaigns/f_w_delimiter_null_v1.py

# Smaller / faster
PYTHONPATH=src python3 -u scripts/campaigns/f_w_delimiter_null_v1.py \
    --random-n 5000 --dictionary-n 5000 --variant vig
```

Artifacts:
- `results/f_w_delimiter_null_v1.json`
- `results/f_w_delimiter_null_v1.md`

## What this null does NOT do

It does not eliminate the W-delimiter hypothesis in segments 0, 2, 3, 5.
It does not address non-additive ciphers. It does not consider physical
overlay or procedural mechanisms outside the feature set. A negative
verdict is a bound on what this specific testable scope can support,
not an unconditional elimination.
