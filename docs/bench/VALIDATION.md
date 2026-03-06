# Benchmark Validation Layer

Post-selection validator that prevents confident wrong answers on short or adversarial ciphertext.

---

## How It Works

After the runner selects a top-1 candidate, `bench/validator.py` computes two independent plausibility signals, combines them into a composite score, then derives a confidence level and `validated` flag.

```
attack() → raw candidates → top-K selection → VALIDATOR → annotated result
                                                  │
                                         ┌────────┴────────┐
                                         │  quadgram score  │
                                         │  wordlist rate   │
                                         │  margin check    │
                                         └────────┬────────┘
                                                  ↓
                                    {plausibility, confidence, validated}
```

The validator is **deterministic** and **score-based only** — no LLM calls, no randomness.

---

## Plausibility Signals

### 1. Quadgram Score (per-character)

Uses `kryptos.kernel.scoring.ngram.get_default_scorer()` (English quadgram log-probabilities from `data/english_quadgrams.json`).

| Range | Meaning |
|---|---|
| > -4.8 | Strong English (e.g. "WEAREDISCOVEREDSAVEYOURSELF" ≈ -4.17) |
| -4.8 to -5.5 | Moderate English (e.g. mixed/noisy text) |
| -5.5 to -6.5 | Weak signal (likely not English) |
| < -6.5 | Almost certainly not English (random ≈ -6.4) |

### 2. Wordlist Hit Rate

Greedy left-to-right longest-match segmentation against `wordlists/english.txt` (370K words, minimum word length 3). Returns `covered_chars / total_chars`.

| Range | Meaning |
|---|---|
| > 0.60 | Plausible English (most characters covered by real words) |
| 0.35–0.60 | Ambiguous |
| < 0.35 | Implausible |

### Composite Plausibility (0–1)

Weighted combination:
- **60% quadgram** (normalized: FLOOR→0.0, HIGH→1.0)
- **40% wordlist** (normalized: 0→0.0, HIGH→1.0)

If quadgram scoring is unavailable (file missing, text too short), falls back to wordlist-only.

---

## Confidence Levels

| Level | `validated` | Meaning |
|---|---|---|
| `high` | `true` | Strong plausibility (≥0.7), adequate margin, sufficient length |
| `medium` | `true` | Moderate plausibility (≥0.4), or high plausibility with small margin or short text |
| `low` | `false` | Weak plausibility (<0.4), or hard-fail on both signals |
| `none` | `false` | No plausibility data, error/empty result, or hard-fail below floor |

### Confidence Reduction Rules

1. **Short text (< 8 chars):** Confidence capped at `medium`, never `high`.
2. **Small margin (< 1.0):** Between top-1 and top-2 candidate scores → confidence reduced by one tier.
3. **Hard fail — quadgram < -6.5:** → confidence `none`, `validated=false`.
4. **Hard fail — quadgram < -5.5 AND wordlist < 0.35:** → confidence `low`, `validated=false`.

---

## Tuning Knobs

All thresholds are module-level constants in `bench/validator.py`:

```python
# Quadgram per-char thresholds
QUADGRAM_HIGH  = -4.8   # above → strong English
QUADGRAM_LOW   = -5.5   # below → weak English
QUADGRAM_FLOOR = -6.5   # below → hard fail

# Wordlist coverage thresholds
WORDLIST_HIGH    = 0.60  # above → plausible
WORDLIST_LOW     = 0.35  # below (with weak quadgram) → hard fail
WORDLIST_MIN_WORD = 3    # shortest word counted

# Margin between top-1 and top-2 scores
MARGIN_SMALL = 1.0       # below → reduce confidence

# Minimum text length for full confidence
MIN_SCORABLE_LEN = 8     # shorter → cap at medium
```

### How to Tune

- **Too many false positives (garbage validates high):** Lower `QUADGRAM_HIGH` (e.g. -4.5) and/or raise `WORDLIST_HIGH` (e.g. 0.70).
- **Too many false negatives (good answers flagged low):** Raise `QUADGRAM_HIGH` (e.g. -5.0) and/or lower `WORDLIST_HIGH` (e.g. 0.50).
- **Short texts over-flagged:** Lower `MIN_SCORABLE_LEN` (e.g. 5).
- **Close-call answers need more caution:** Raise `MARGIN_SMALL` (e.g. 2.0).

---

## Output Format

The validator adds a `validation` key to each benchmark result:

```json
{
  "case_id": "tier0_caesar_001",
  "status": "success",
  "predicted_plaintext": "WEAREDISCOVEREDSAVEYOURSELF",
  "validation": {
    "plausibility": 0.9312,
    "confidence": "high",
    "validated": true,
    "wordlist_coverage": 0.7308,
    "quadgram_per_char": -4.1666,
    "margin": 50.0
  }
}
```

Fields in `validation`:
- `plausibility` (float, 0–1): Composite English-likeness score
- `confidence` (string): `"high"` | `"medium"` | `"low"` | `"none"`
- `validated` (bool): Whether the answer passes validation
- `wordlist_coverage` (float, 0–1): Fraction of chars matched to dictionary words
- `quadgram_per_char` (float, optional): Average log-probability per character
- `margin` (float, optional): Score gap between top-1 and top-2 candidates

---

## Integration Points

### Runner (automatic)

The runner calls `validate_result()` on every successful result automatically. No configuration needed.

### Programmatic Use

```python
from bench.validator import validate_candidate

vr = validate_candidate(
    "WEAREDISCOVEREDSAVEYOURSELF",
    best_score=100.0,
    runner_up_score=50.0,
)
print(vr.confidence)   # "high"
print(vr.validated)     # True
print(vr.plausibility)  # 0.93
```

### Scorer Integration

The `bench/scorer.py` module reads the `validation` field from results. Downstream reports can filter or group by confidence level.

---

## Design Decisions

1. **Self-contained wordlist segmentation.** The greedy longest-match is imperfect but sufficient as a plausibility signal. It's O(n × max_word_len) and doesn't require NLP libraries.

2. **Quadgram as primary signal.** Quadgram scoring is the standard cryptanalysis fitness function — it's fast, well-calibrated, and already available in the repo.

3. **Two-signal voting.** Neither quadgram nor wordlist alone is reliable for short or adversarial text. Combining them reduces false positives (bait cribs that score well on one metric but not both).

4. **Margin check.** When the top two candidates are close in score, the "best" answer is uncertain. Reducing confidence in this case pushes consumers toward examining top-K rather than trusting top-1.

5. **No refactoring of attack scripts.** The validator operates post-hoc on results. Scripts don't need to change.
