# kryptos.language — grammar prior for K4

A constrained **soft prior** for ranking short phrase candidates around the
known K4 anchors (`EASTNORTHEAST` at 21-33, `BERLINCLOCK` at 63-73).

## What this is

- A rule-based scorer over a small, hand-curated vocabulary tagged with POS.
- A set of phrase templates for directive / status-report / telegraphic /
  hybrid operational English.
- Transparent component breakdowns: every score is the weighted linear
  combination of documented components.

## What this is NOT

- Not a decoder. It does not operate on ciphertext.
- Not a theory generator. It does not invent plaintext.
- Not a plaintext identifier. It cannot promote any fill to "new crib"
  status. A high grammar prior is a grammatical plausibility signal only.
- Not a language model in the statistical-corpus sense. There is no
  quadgram or n-gram scoring here — see `kryptos.kernel.scoring` for that.

## Register models

Four hand-defined registers live in `communique_models.py`:

| Register       | Article suppression | Initial POS preference       |
|----------------|---------------------|------------------------------|
| directive      | 0.55                | VERB_OP, DIRECTION           |
| status_report  | 0.85                | NOUN_STATUS                  |
| telegraphic    | 0.95                | VERB_OP, NOUN_STATUS, NOUN_LOC |
| hybrid         | 0.70                | mixed                        |

## POS tag set

`PREP, ART, AUX, VERB_OP, NOUN_LOC, NOUN_STATUS, DIRECTION, ADJ, ADV,
PARTICLE, PRONOUN, CONJ, NUM` — defined once in `communique_models.POS_TAGS`.

## Scoring components

All components live in `[0.0, 1.0]` and are combined with `DEFAULT_WEIGHTS`:

```
slot_length_compat        1.5
pos_compat                2.0
template_fit              1.5
anchor_context_plausibility 2.5
register_plausibility     1.5
article_suppression_consistency 0.5
semantic_coherence        1.0
```

The aggregate is the weight-normalized sum — no hidden factors.

## Extending inventories

Add entries to `inventories.py`. Every entry must specify:

- a word (UPPERCASE)
- a single POS tag from `POS_TAGS`
- per-register prior weights in `[0.0, 1.0]`
- optional notes

No external dependencies. No corpus look-ups. Determinism is the point.

## Example queries

```
PYTHONPATH=src python3 scripts/tools/k4_grammar_probe.py \
    --query left-context --anchor BERLINCLOCK --slot-length 2 --role PREP --top-k 10

PYTHONPATH=src python3 scripts/tools/k4_grammar_probe.py \
    --query compare --phrases "AT BERLINCLOCK" "TO BERLINCLOCK" "NEAR BERLINCLOCK"

PYTHONPATH=src python3 scripts/tools/k4_grammar_probe.py \
    --query sequence --text "ASSET COMPROMISED MEET AT BERLINCLOCK GO EASTNORTHEAST"
```

## Disclaimer

Grammar prior is a soft signal only. It does NOT identify plaintext. Do not
promote any candidate to crib status without independent cryptanalytic
support.
